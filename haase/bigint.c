// Author: Bjoern Haase
//
// License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)

#include "../include/bigint.h"

// If we collect all input and result data into one single struct that may be
// accessed by one single pointer, we reduce register pressure for the compiler.
// This speeds up 128 bit multiply significantly on plain C versions of
// 128 bit multiply on cortex M0

typedef struct _ST_mpy64x64_params
{
    UN_64bitValue  x;
    UN_64bitValue  y;
    UN_128bitValue result;
} ST_mpy64x64_params;

FORCE_INLINE static uint64_t
multiply32x32(
    uint32_t x,
    uint32_t y
);

// static uint32_t FORCE_INLINE
// multiply32x32_upperWord (uint32_t x, uint32_t y);

FORCE_INLINE void 
multiply32x64(
    UN_96bitValue* result,
    uint32_t         x,
    const uint64_t*  py
);

FORCE_INLINE void
multiply64x64(
    UN_128bitValue* r,
    const uint64_t*   x,
    const uint64_t*   y
);

FORCE_INLINE static void
square64(
    UN_128bitValue* r,
    const uint64_t*   pu64_x
);

// This implementation may access all data and results by
// use of one single pointer. This reduces register pressure considerably
// and helps the compiler getting good results.
FORCE_INLINE static void
multiply64x64_paramStruct(
    ST_mpy64x64_params* params
);

static uint64_t
multiply32x32(
    uint32_t x,
    uint32_t y
)
{
    uint64_t r = ((uint32_t)((uint16_t)x)) * ((uint16_t)y)
               | (
        (
            (uint64_t)((x >> 16) * (y >> 16))
        ) << 32
               );

    r += ((uint64_t)(((uint16_t)x) * (y >> 16))) << 16;
    r += ((uint64_t)(((uint16_t)y) * (x >> 16))) << 16;
    return r;
}

void
multiply32x64(
    UN_96bitValue* result,
    uint32_t         x,
    const uint64_t*  py
)
{
    const UN_64bitValue* y = (const UN_64bitValue*)py;

    uint64_t tmp;

    result->as_uint64_t[0] = multiply32x32(x, y->as_uint32_t[0]);
    tmp = multiply32x32(x, y->as_uint32_t[1]);
    tmp += result->as_uint32_t[1];
    result->as_uint32_t[1] = (uint32_t)tmp;
    result->as_uint32_t[2] = (uint32_t)(tmp >> 32);
}

/// Multiply two 64 bit values with a 128 bit result. Uses the karatsuba method. Is faster than
/// the texbook variant mainly because less memory accesses are needed (2 cycles on Cortex M0).
void
multiply64x64(
    UN_128bitValue* r,
    const uint64_t*   pu64_x,
    const uint64_t*   pu64_y
)
{
    uint32_t* au32_x = (uint32_t*)pu64_x;
    uint32_t* au32_y = (uint32_t*)pu64_y;

    uint16_t* au16_x = (uint16_t*)au32_x;
    uint16_t* au16_y = (uint16_t*)au32_y;

    {
        uint32_t lowB;
        uint32_t highB;
        uint32_t lowA;
        uint32_t highA;

        {
            // calculate B
            uint64_t b = ((uint32_t)au16_x[0]) * au16_y[0]
                       | ((uint64_t)(((uint32_t)au16_x[1]) * au16_y[1]) << 32);
            b += ((uint64_t)(((uint32_t)au16_x[0]) * au16_y[1])) << 16;
            b += ((uint64_t)(((uint32_t)au16_x[1]) * au16_y[0])) << 16;
            lowB = (uint32_t)b;
            {
                r->as_uint32_t[0] = lowB;
            }

            highB = (uint32_t)(b >> 32);
        }

        {
            uint64_t a;
            // calculate A
            a = ((uint32_t)au16_x[3]) * au16_y[2];
            a += ((uint32_t)au16_x[2]) * au16_y[3];
            a <<= 16;
            a += ((uint32_t)au16_x[2]) * au16_y[2];

            lowA = (uint32_t)a;
            highA = (uint32_t)(a >> 32);
        }
        highA += ((uint32_t)au16_x[3]) * au16_y[3];

        // OK, we now have calculated the two first products.
        // the lowest 4 bytes also have been finished now.

        // accumulate the rest of the first two products
        // in the result location.

        {
            uint64_t accu;

            accu = lowB;
            accu += highB;
            accu += lowA;

            r->as_uint32_t[1] = (uint32_t)accu;
            accu >>= 32;

            accu += highB;
            accu += lowA;
            accu += highA;

            r->as_uint32_t[2] = (uint32_t)accu;
            {
                uint32_t restOfAccu = (uint32_t)(accu >> 32);
                // accu no longer used.

                restOfAccu += highA;
                r->as_uint32_t[3] = restOfAccu;
            }
        }
    }

    // What remains is the more complicated third
    // term in the kasutra formulas.

    {
        uint32_t lowAlpha;
        uint32_t lowBeta;
        {
            int32_t highAlpha;
            int32_t highBeta;

            {
                int64_t alpha = au32_x[0];
                alpha -= au32_x[1];

                lowAlpha = (uint32_t)alpha;
                highAlpha = (int32_t)(alpha >> 32);
            }

            {
                // note the inverted sign, so that we simply may add.
                int64_t beta = au32_y[1];
                beta -= au32_y[0];

                lowBeta = (uint32_t)beta;
                highBeta = (int32_t)(beta >> 32);
            }

            // accumulate all with high alpha and beta corresponding
            // parts.

            {
                int64_t accu = r->as_uint64_t[1];
                accu -= highBeta & lowAlpha;
                accu -= highAlpha & lowBeta;
                r->as_uint32_t[2] = (uint32_t)accu;
                {
                    int32_t accuHigh = (int32_t)(accu >> 32);
                    accuHigh += highBeta * highAlpha;
                    r->as_uint32_t[3] = accuHigh;
                }
            }
            // high alpha and high beta no longer needed.
        }

        {
            uint32_t lowC;
            uint32_t highC;
            {
                uint64_t c;
                c = (lowAlpha & 0xffff) * (lowBeta >> 16);
                c += (lowBeta & 0xffff) * (lowAlpha >> 16);
                c <<= 16;
                c += (lowAlpha & 0xffff) * (lowBeta & 0xffff);
                lowC = (uint32_t)c;
                highC = (uint32_t)(c >> 32);
            }
            highC += (lowAlpha >> 16) * (lowBeta >> 16);

            // accumulate the last term.

            {
                uint64_t accu = r->as_uint32_t[1];
                accu += lowC;
                r->as_uint32_t[1] = (uint32_t)accu;

                accu >>= 32;
                accu += r->as_uint64_t[1];
                accu += highC;

                r->as_uint64_t[1] = accu;
            }
        }
    }
}

/// Multiply two 64 bit values with a 128 bit result. Uses the karatsuba method. Is faster than
/// the texbook variant mainly because less memory accesses are needed (2 cycles on Cortex M0).
FORCE_INLINE void
multiply64x64_paramStruct(
    ST_mpy64x64_params* params
)
{
    // This call will be inlined. The compiler will exploit the fact that all data may
    // be accessed by one single pointer.
    multiply64x64(&params->result,
                  &params->x.as_uint64_t[0],
                  &params->y.as_uint64_t[0]);
}

FORCE_INLINE void
square64(
    UN_128bitValue* r,
    const uint64_t*   pu64_x
)
{
    uint32_t* au32_x = (uint32_t*)pu64_x;
    uint16_t* au16_x = (uint16_t*)au32_x;

    uint64_t accu = ((uint32_t)au16_x[0]) * au16_x[0];

    {
        uint64_t tmp64 = ((uint32_t)au16_x[1]) * au16_x[0];
        accu += tmp64 << 17;
    }

    r->as_uint32_t[0] = (uint32_t)accu;
    accu >>= 32;

    accu += ((uint32_t)au16_x[1]) * au16_x[1];
    {
        uint32_t tmp32 = ((uint32_t)au16_x[0]) * au16_x[2];
        accu += tmp32;
        accu += tmp32;
    }
    {
        uint64_t tmp64 = ((uint32_t)au16_x[1]) * au16_x[2];
        tmp64 += ((uint32_t)au16_x[0]) * au16_x[3];
        accu += tmp64 << 17;
    }
    r->as_uint32_t[1] = (uint32_t)accu;
    accu >>= 32;

    accu += ((uint32_t)au16_x[2]) * au16_x[2];
    {
        uint32_t tmp32 = ((uint32_t)au16_x[1]) * au16_x[3];
        accu += tmp32;
        accu += tmp32;
    }
    {
        uint64_t tmp64 = ((uint32_t)au16_x[2]) * au16_x[3];
        accu += tmp64 << 17;
    }
    r->as_uint32_t[2] = (uint32_t)accu;

    r->as_uint32_t[3] = ((uint32_t)(accu >> 32)) + ((uint32_t)au16_x[3]) * au16_x[3];
}

#ifndef CRYPTO_HAS_ASM_MPY_96

void
multiply96x96_c(
    UN_192bitValue*      result,
    const UN_96bitValue* x,
    const UN_96bitValue* y
)
{
    UN_96bitValue tmp1;
    UN_96bitValue tmp2;
    uint8_t         ctr;
    uint64_t        accu = 0;

    multiply64x64(&result->as_128_bitValue[0],
                  &x->as_uint64_t[0],
                  &y->as_uint64_t[0]);
    result->as_uint64_t[2] = multiply32x32(x->as_uint32_t[2], y->as_uint32_t[2]);

    multiply32x64(&tmp1, y->as_uint32_t[2], &x->as_uint64_t[0]);
    multiply32x64(&tmp2, x->as_uint32_t[2], &y->as_uint64_t[0]);

    for (ctr = 0; ctr < 3; ctr++)
    {
        accu += result->as_uint32_t[2 + ctr];
        accu += tmp1.as_uint32_t[ctr];
        accu += tmp2.as_uint32_t[ctr];
        result->as_uint32_t[2 + ctr] = (uint32_t)accu;
        accu >>= 32;
    }
    result->as_uint32_t[5] += (uint32_t)accu;
}

#endif // #ifndef CRYPTO_HAS_ASM_MPY_96

#ifndef CRYPTO_HAS_ASM_SQR_96

void
square96_c(
    UN_192bitValue*      result,
    const UN_96bitValue* x
)
{
    UN_96bitValue tmp;
    uint8_t         ctr;
    uint64_t        accu = 0;

    square64(&result->as_128_bitValue[0], &x->as_uint64_t[0]);
    result->as_uint64_t[2] = multiply32x32(x->as_uint32_t[2], x->as_uint32_t[2]);

    multiply32x64(&tmp, x->as_uint32_t[2], &x->as_uint64_t[0]);

    for (ctr = 0; ctr < 3; ctr++)
    {
        accu += result->as_uint32_t[2 + ctr];
        accu += tmp.as_uint32_t[ctr];
        accu += tmp.as_uint32_t[ctr];
        result->as_uint32_t[2 + ctr] = (uint32_t)accu;
        accu >>= 32;
    }
    result->as_uint32_t[5] += (uint32_t)accu;
}

#endif // #ifndef CRYPTO_HAS_ASM_MPY_96

#ifndef CRYPTO_HAS_ASM_SQR_128

void
square128_c(
    UN_256bitValue*       result,
    const UN_128bitValue* x
)
{
    square64(&result->as_128_bitValue[0], &x->as_uint64_t[0]);
    square64(&result->as_128_bitValue[1], &x->as_uint64_t[1]);

    {
        UN_128bitValue temp;
        uint64_t         accu;
        multiply64x64(&temp, &x->as_uint64_t[0], &x->as_uint64_t[1]);

        accu = result->as_uint32_t[2];
        accu += temp.as_uint32_t[0];
        accu += temp.as_uint32_t[0];
        result->as_uint32_t[2] = (uint32_t)accu;
        accu >>= 32;

        accu += result->as_uint32_t[3];
        accu += temp.as_uint32_t[1];
        accu += temp.as_uint32_t[1];
        result->as_uint32_t[3] = (uint32_t)accu;
        accu >>= 32;

        accu += result->as_uint32_t[4];
        accu += temp.as_uint32_t[2];
        accu += temp.as_uint32_t[2];
        result->as_uint32_t[4] = (uint32_t)accu;
        accu >>= 32;

        accu += result->as_uint32_t[5];
        accu += temp.as_uint32_t[3];
        accu += temp.as_uint32_t[3];
        result->as_uint32_t[5] = (uint32_t)accu;
        accu >>= 32;

        accu += result->as_uint32_t[6];
        result->as_uint32_t[6] = (uint32_t)accu;
        accu >>= 32;

        result->as_uint32_t[7] += accu >> 32;
    }
}

#endif // #ifndef CRYPTO_HAS_ASM_SQR_128

#ifndef CRYPTO_HAS_ASM_MPY_128

// We use Karatsuba to map 128x128 on 64x64
void
multiply128x128_c(
    UN_256bitValue*       result,
    const UN_128bitValue* x,
    const UN_128bitValue* y
)
{
    ST_mpy64x64_params m1;
    ST_mpy64x64_params m2;
    ST_mpy64x64_params m3;

    int32_t m3_msw_x;
    int32_t m3_msw_y;

    // First step: Copy the operands in prepared stack variables
    // Result: *x and *y will be dead after this procedure.

    {
        uint32_t reg;
        int64_t  accu;

        reg = x->as_uint32_t[2];
        m2.x.as_uint32_t[0] = reg;
        accu = reg;

        reg = x->as_uint32_t[0];
        m1.x.as_uint32_t[0] = reg;
        accu -= reg;

        m3.x.as_uint32_t[0] = (uint32_t)accu;
        accu >>= 32;

        reg = x->as_uint32_t[3];
        m2.x.as_uint32_t[1] = reg;
        accu += reg;

        reg = x->as_uint32_t[1];
        m1.x.as_uint32_t[1] = reg;
        accu -= reg;

        m3.x.as_uint32_t[1] = (uint32_t)accu;
        m3_msw_x = (int32_t)(accu >> 32);
    }

    {
        uint32_t reg;
        int64_t  accu;

        reg = y->as_uint32_t[0];
        m1.y.as_uint32_t[0] = reg;
        accu = reg;

        reg = y->as_uint32_t[2];
        m2.y.as_uint32_t[0] = reg;
        accu -= reg;

        m3.y.as_uint32_t[0] = (uint32_t)accu;
        accu >>= 32;

        reg = y->as_uint32_t[1];
        m1.y.as_uint32_t[1] = reg;
        accu += reg;

        reg = y->as_uint32_t[3];
        m2.y.as_uint32_t[1] = reg;
        accu -= reg;

        m3.y.as_uint32_t[1] = (uint32_t)accu;
        m3_msw_y = (int32_t)(accu >> 32);
    }

    // Now calculate the three products.
    multiply64x64_paramStruct(&m1);
    multiply64x64_paramStruct(&m2);
    multiply64x64_paramStruct(&m3);

    // Now accumulate the results.
    {
        uint32_t tmp1;
        uint32_t tmp2;
        int64_t  accu;

        tmp1 = m1.result.as_uint32_t[0];
        result->as_uint32_t[0] = tmp1;

        tmp2 = m1.result.as_uint32_t[1];
        result->as_uint32_t[1] = tmp2;

        accu = tmp1;
        accu += m1.result.as_uint32_t[2];
        accu += m2.result.as_uint32_t[0];
        accu += m3.result.as_uint32_t[0];

        result->as_uint32_t[2] = (uint32_t)accu;
        accu >>= 32;

        accu += tmp2;
        accu += m1.result.as_uint32_t[3];
        accu += m2.result.as_uint32_t[1];
        accu += m3.result.as_uint32_t[1];

        result->as_uint32_t[3] = (uint32_t)accu;
        accu >>= 32;

        accu += m2.result.as_uint32_t[0];
        accu += m1.result.as_uint32_t[2];
        accu += m2.result.as_uint32_t[2];
        accu += m3.result.as_uint32_t[2];

        accu -= (((uint32_t)m3_msw_y) & m3.x.as_uint32_t[0]);
        accu -= (((uint32_t)m3_msw_x) & m3.y.as_uint32_t[0]);

        result->as_uint32_t[4] = (uint32_t)accu;
        accu >>= 32;

        accu += m2.result.as_uint32_t[1];
        accu += m1.result.as_uint32_t[3];
        accu += m2.result.as_uint32_t[3];
        accu += m3.result.as_uint32_t[3];

        accu -= (((uint32_t)m3_msw_y) & m3.x.as_uint32_t[1]);
        accu -= (((uint32_t)m3_msw_x) & m3.y.as_uint32_t[1]);

        result->as_uint32_t[5] = (uint32_t)accu;
        accu >>= 32;

        accu += (m3_msw_x * m3_msw_y);
        accu += m2.result.as_uint32_t[2];

        result->as_uint32_t[6] = (uint32_t)(accu);
        result->as_uint32_t[7] = ((uint32_t)(accu >> 32)) + m2.result.as_uint32_t[3];
    }
}

#endif // ifndef CRYPTO_HAS_ASM_MPY_128


#ifndef CRYPTO_HAS_ASM_MPY_192

// We use Karatsuba to map 192x192 on 96x96
void
multiply192x192_c(
    UN_384bitValue*       result,
    const UN_192bitValue* x,
    const UN_192bitValue* y
)
{
// high                              low
// +--------+--------+ +--------+--------+
// |      x1*y1      | |      x0*y0      |
// +--------+--------+ +--------+--------+
// +--------+--------+
// add |      x1*y1      |
// +--------+--------+
// +--------+--------+
// add |      x0*y0      |
// +--------+--------+
// +--------+--------+
// add | (x1-x0)*(y0-y1) |
// +--------+--------+

    // Store the products x1 * y1, and x0 * y0 in the buffer for the final result.

    // dispatcher == either the ASM or C variant is chosen.
    multiply96x96            ((UN_192bitValue*)&result->as_uint32_t[0],
                             (const UN_96bitValue*)&x->as_uint32_t[0],
                             (const UN_96bitValue*)&y->as_uint32_t[0]);
    multiply96x96            ((UN_192bitValue*)&result->as_uint32_t[6],
                             (const UN_96bitValue*)&x->as_uint32_t[3],
                             (const UN_96bitValue*)&y->as_uint32_t[3]);

    {
        UN_96bitValue deltaX;
        int32_t         upperWordDeltaX;
        UN_96bitValue deltaY;
        int32_t         upperWordDeltaY;

        {
            int64_t accu = x->as_uint32_t[3];
            accu -= x->as_uint32_t[0];
            deltaX.as_uint32_t[0] = (uint32_t)accu;

            accu >>= 32;
            accu += x->as_uint32_t[4];
            accu -= x->as_uint32_t[1];
            deltaX.as_uint32_t[1] = (uint32_t)accu;

            accu >>= 32;
            accu += x->as_uint32_t[5];
            accu -= x->as_uint32_t[2];
            deltaX.as_uint32_t[2] = (uint32_t)accu;

            upperWordDeltaX = (int32_t)(accu >> 32);
        }

        {
            // use inverted sign in comparison to deltax, so that we may always add the
            // value
            int64_t accu = y->as_uint32_t[0];
            accu -= y->as_uint32_t[3];
            deltaY.as_uint32_t[0] = (uint32_t)accu;

            accu >>= 32;
            accu += y->as_uint32_t[1];
            accu -= y->as_uint32_t[4];
            deltaY.as_uint32_t[1] = (uint32_t)accu;

            accu >>= 32;
            accu += y->as_uint32_t[2];
            accu -= y->as_uint32_t[5];
            deltaY.as_uint32_t[2] = (uint32_t)accu;

            upperWordDeltaY = (int32_t)(accu >> 32);
        }

        {
            UN_192bitValue temp;

            // either the ASM or C variant is chosen.
            multiply96x96(&temp, &deltaX, &deltaY);
            {
                int32_t ctr;

                int64_t accu = 0;

                for (ctr = 0; ctr < 3; ctr++)
                {
                    accu += result->as_uint32_t[ctr]; // lower half term of x0 * y0
                    accu += result->as_uint32_t[3 + ctr]; // upper half term of x0 * y0
                    accu += result->as_uint32_t[6 + ctr]; // lower half term of x1 * y1
                    accu += temp.as_uint32_t[ctr]; // lower half term of difference product
                    temp.as_uint32_t[ctr] = (uint32_t)accu; // store the result temporary here since we will need the content of the result buffer.
                    accu >>= 32;
                }

                for (ctr = 0; ctr < 3; ctr++)
                {
                    accu += temp.as_uint32_t[ctr + 3]; // upper half term of difference product
                    accu -= deltaY.as_uint32_t[ctr] & ((uint32_t)upperWordDeltaX);
                    accu -= deltaX.as_uint32_t[ctr] & ((uint32_t)upperWordDeltaY);

                    accu += result->as_uint32_t[3 + ctr]; // upper half term of x0 * y0
                    accu += result->as_uint32_t[9 + ctr]; // upper half term of x1 * y1
                    accu += result->as_uint32_t[6 + ctr]; // lower half term of x1 * y1

                    result->as_uint32_t[6 + ctr] = (uint32_t)accu;
                    accu >>= 32;
                }
                accu += upperWordDeltaX * upperWordDeltaY;

                for (ctr = 0; ctr < 2; ctr++)
                {
                    accu += result->as_uint32_t[9 + ctr];
                    result->as_uint32_t[9 + ctr] = (uint32_t)accu;
                    accu >>= 32;
                }
                result->as_uint32_t[11] += (uint32_t)accu;

                // now copy the four lower words from the temp buffer.
                result->as_uint32_t[3] = temp.as_uint32_t[0];
                result->as_uint32_t[4] = temp.as_uint32_t[1];
                result->as_uint32_t[5] = temp.as_uint32_t[2];
            }
        }
    }
}
#endif //#ifndef CRYPTO_HAS_ASM_MPY_96

#ifndef CRYPTO_HAS_ASM_SQR_192

void
square192_c (
    UN_384bitValue*       result,
    const UN_192bitValue* x
)
{
    // dispatcher == either the ASM or C variant is chosen.
    square96((UN_192bitValue*)&result->as_uint32_t[0],
             (const UN_96bitValue*)&x->as_uint32_t[0]);
    square96((UN_192bitValue*)&result->as_uint32_t[6],
             (const UN_96bitValue*)&x->as_uint32_t[3]);

    {
        UN_192bitValue temp;
        int32_t          ctr;
        uint64_t         accu = 0;

        // dispatcher == either the ASM or C variant is chosen.
        multiply96x96(&temp,
                      (const UN_96bitValue*)&x->as_uint32_t[0],
                      (const UN_96bitValue*)&x->as_uint32_t[3]);

        for (ctr = 0; ctr < 6; ctr++)
        {
            accu += result->as_uint32_t[3 + ctr];
            accu += temp.as_uint32_t[ctr];
            accu += temp.as_uint32_t[ctr];
            result->as_uint32_t[3 + ctr] = (uint32_t)accu;
            accu >>= 32;
        }

        for (ctr = 0; ctr < 2; ctr++)
        {
            accu += result->as_uint32_t[9 + ctr];
            result->as_uint32_t[9 + ctr] = (uint32_t)accu;
            accu >>= 32;
        }
        result->as_uint32_t[11] += accu >> 32;
    }
}
#endif // #ifdef CRYPTO_HAS_ASM_SQR_192

#ifndef CRYPTO_HAS_ASM_MPY_256

// We use Karatsuba to map 256x256 on 128x128
void
multiply256x256_c(
    UN_512bitValue*       result,
    const UN_256bitValue* x,
    const UN_256bitValue* y
)
{
// high                              low
// +--------+--------+ +--------+--------+
// |      x1*y1      | |      x0*y0      |
// +--------+--------+ +--------+--------+
// +--------+--------+
// add |      x1*y1      |
// +--------+--------+
// +--------+--------+
// add |      x0*y0      |
// +--------+--------+
// +--------+--------+
// add | (x1-x0)*(y0-y1) |
// +--------+--------+

    // Store the products x1 * y1, and x0 * y0 in the buffer for the final result.

    // dispatcher == either the ASM or C variant is chosen.
    multiply128x128(&result->as_256_bitValue[0],
                    &x->as_128_bitValue[0], &y->as_128_bitValue[0]);
    multiply128x128(&result->as_256_bitValue[1],
                    &x->as_128_bitValue[1], &y->as_128_bitValue[1]);

    {
        UN_128bitValue deltaX;
        int32_t          upperWordDeltaX;
        UN_128bitValue deltaY;
        int32_t          upperWordDeltaY;

        {
            int64_t accu = x->as_uint32_t[4];
            accu -= x->as_uint32_t[0];
            deltaX.as_uint32_t[0] = (uint32_t)accu;

            accu >>= 32;
            accu += x->as_uint32_t[5];
            accu -= x->as_uint32_t[1];
            deltaX.as_uint32_t[1] = (uint32_t)accu;

            accu >>= 32;
            accu += x->as_uint32_t[6];
            accu -= x->as_uint32_t[2];
            deltaX.as_uint32_t[2] = (uint32_t)accu;

            accu >>= 32;
            accu += x->as_uint32_t[7];
            accu -= x->as_uint32_t[3];
            deltaX.as_uint32_t[3] = (uint32_t)accu;

            upperWordDeltaX = (int32_t)(accu >> 32);
        }

        {
            // use inverted sign in comparison to deltax, so that we may always add the
            // value
            int64_t accu = y->as_uint32_t[0];
            accu -= y->as_uint32_t[4];
            deltaY.as_uint32_t[0] = (uint32_t)accu;

            accu >>= 32;
            accu += y->as_uint32_t[1];
            accu -= y->as_uint32_t[5];
            deltaY.as_uint32_t[1] = (uint32_t)accu;

            accu >>= 32;
            accu += y->as_uint32_t[2];
            accu -= y->as_uint32_t[6];
            deltaY.as_uint32_t[2] = (uint32_t)accu;

            accu >>= 32;
            accu += y->as_uint32_t[3];
            accu -= y->as_uint32_t[7];
            deltaY.as_uint32_t[3] = (uint32_t)accu;

            upperWordDeltaY = (int32_t)(accu >> 32);
        }

        {
            UN_256bitValue temp;

            // either the ASM or C variant is chosen.
            multiply128x128 (&temp, &deltaX, &deltaY);
            {
                int32_t ctr;

                int64_t accu = 0;

                for (ctr = 0; ctr < 4; ctr++)
                {
                    accu += result->as_uint32_t[ctr]; // lower half term of x0 * y0
                    accu += result->as_uint32_t[4 + ctr]; // upper half term of x0 * y0
                    accu += result->as_uint32_t[8 + ctr]; // lower half term of x1 * y1
                    accu += temp.as_uint32_t[ctr]; // lower half term of difference product
                    temp.as_uint32_t[ctr] = (uint32_t)accu; // store the result temporary here since we will need the content of the result buffer.
                    accu >>= 32;
                }

                for (ctr = 0; ctr < 4; ctr++)
                {
                    accu += temp.as_uint32_t[ctr + 4]; // upper half term of difference product
                    accu -= deltaY.as_uint32_t[ctr] & ((uint32_t)upperWordDeltaX);
                    accu -= deltaX.as_uint32_t[ctr] & ((uint32_t)upperWordDeltaY);

                    accu += result->as_uint32_t[4 + ctr]; // upper half term of x0 * y0
                    accu += result->as_uint32_t[12 + ctr]; // upper half term of x1 * y1
                    accu += result->as_uint32_t[8 + ctr]; // lower half term of x1 * y1

                    result->as_uint32_t[8 + ctr] = (uint32_t)accu;
                    accu >>= 32;
                }
                accu += upperWordDeltaX * upperWordDeltaY;

                for (ctr = 0; ctr < 3; ctr++)
                {
                    accu += result->as_uint32_t[12 + ctr];
                    result->as_uint32_t[12 + ctr] = (uint32_t)accu;
                    accu >>= 32;
                }
                result->as_uint32_t[15] += (uint32_t)accu;

                // now copy the four lower words from the temp buffer.
                result->as_uint32_t[4] = temp.as_uint32_t[0];
                result->as_uint32_t[5] = temp.as_uint32_t[1];
                result->as_uint32_t[6] = temp.as_uint32_t[2];
                result->as_uint32_t[7] = temp.as_uint32_t[3];
            }
        }
    }
}

#endif //#ifndef CRYPTO_HAS_ASM_MPY_256

#ifndef CRYPTO_HAS_ASM_SQR_256

void
square256_c(
    UN_512bitValue*       result,
    const UN_256bitValue* x
)
{
    // dispatcher == either the ASM or C variant is chosen.
    square128 (&result->as_256_bitValue[0], &x->as_128_bitValue[0]);
    square128 (&result->as_256_bitValue[1], &x->as_128_bitValue[1]);

    {
        UN_256bitValue temp;
        int32_t          ctr;
        uint64_t         accu = 0;

        // dispatcher == either the ASM or C variant is chosen.
        multiply128x128(&temp,
                        &x->as_128_bitValue[0],
                        &x->as_128_bitValue[1]);

        for (ctr = 0; ctr < 8; ctr++)
        {
            accu += result->as_uint32_t[4 + ctr];
            accu += temp.as_uint32_t[ctr];
            accu += temp.as_uint32_t[ctr];
            result->as_uint32_t[4 + ctr] = (uint32_t)accu;
            accu >>= 32;
        }

        for (ctr = 0; ctr < 3; ctr++)
        {
            accu += result->as_uint32_t[12 + ctr];
            result->as_uint32_t[12 + ctr] = (uint32_t)accu;
            accu >>= 32;
        }
        result->as_uint32_t[15] += accu >> 32;
    }
}

#endif // #ifndef CRYPTO_HAS_ASM_SQR_256


/// Will be required for the barret reduction for the "scalar" prime modulo calculations.
void
multiply288x288(
    UN_576bitValue*       r,
    const UN_288bitValue* x,
    const UN_288bitValue* y
)
{
    multiply256x256(
                    &r->as_512_bitValue[0],
                    &x->as_256_bitValue[0],
                    &y->as_256_bitValue[0]);

    {
        uint64_t accu = multiply32x32(x->as_uint32_t[8], y->as_uint32_t[8]);
        r->as_uint32_t[16] = (uint32_t)accu;
        r->as_uint32_t[17] = (uint32_t)(accu >> 32);
    }

    {
        uint32_t ctr;
        uint64_t accu = 0;
        uint64_t mpy_result;

        for (ctr = 0; ctr < 8; ctr++)
        {
            accu += r->as_uint32_t[8 + ctr];
            mpy_result = multiply32x32(x->as_uint32_t[ctr], y->as_uint32_t[8]);
            accu += (uint32_t)mpy_result;

            r->as_uint32_t[8 + ctr] = (uint32_t)accu;
            accu >>= 32;
            accu += mpy_result >> 32;
        }
        accu += r->as_uint32_t[16];
        r->as_uint32_t[16] = (uint32_t)accu;
        accu >>= 32;
        r->as_uint32_t[17] += (uint32_t) accu;

        accu = 0;

        for (ctr = 0; ctr < 8; ctr++)
        {
            accu += r->as_uint32_t[8 + ctr];
            mpy_result = multiply32x32(y->as_uint32_t[ctr], x->as_uint32_t[8]);
            accu += (uint32_t)mpy_result;
            r->as_uint32_t[8 + ctr] = (uint32_t)accu;
            accu >>= 32;
            accu += mpy_result >> 32;
        }
        accu += r->as_uint32_t[16];
        r->as_uint32_t[16] = (uint32_t)accu;
        r->as_uint32_t[17] += (uint32_t)(accu >> 32);
    }
}

/// Was required for an old inefficient version of the poly1305 authentication algorithm.
/// but is still kept.
void
multiply136x136(
    UN_272bitValue*       r,
    const UN_136bitValue* x,
    const UN_136bitValue* y
)
{
    uint64_t accu;

    multiply128x128(&r->as_256_bitValue[0],
                    &x->as_128_bitValue[0],
                    &y->as_128_bitValue[0]);

    {
        uint8_t xmax = x->as_uint8_t[16];
        uint8_t ymax = y->as_uint8_t[16];
        uint8_t ctr;

        accu = 0;

        for (ctr = 0; ctr < 4; ctr++)
        {
            accu += r->as_uint32_t[4 + ctr];
            accu += xmax * ((uint32_t)y->as_uint16_t[2 * ctr]);
            accu +=
                ((uint64_t)(xmax * ((uint32_t)y->as_uint16_t[1 + 2 * ctr]))) << 16;
            accu += ymax * ((uint32_t)x->as_uint16_t[2 * ctr]);
            accu +=
                ((uint64_t)(ymax * ((uint32_t)x->as_uint16_t[1 + 2 * ctr]))) << 16;
            r->as_uint32_t[4 + ctr] = (uint32_t)accu;
            accu >>= 32;
        }
        accu += ((uint16_t)xmax) * ((uint16_t)ymax);
        r->as_uint16_t[16] = (uint16_t)accu;
    }
}

void
setone_256bitvalue(
    UN_256bitValue* dest
)
{
    uint32_t ctr;

    dest->as_uint32_t[0] = 1;

    for (ctr = 1; ctr < 8; ctr++)
    {
        dest->as_uint32_t[ctr] = 0;
    }
}

void
setzero_256bitvalue(
    UN_256bitValue* dest
)
{
    uint32_t ctr;

    for (ctr = 0; ctr < 8; ctr++)
    {
        dest->as_uint32_t[ctr] = 0;
    }
}

void
cpy_256bitvalue(
    UN_256bitValue*       dest,
    const UN_256bitValue* source
)
{
    uint32_t ctr;

    for (ctr = 0; ctr < 8; ctr++)
    {
        dest->as_uint32_t[ctr] = source->as_uint32_t[ctr];
    }
}

void
cpy_192bitvalue(
    UN_192bitValue*       dest,
    const UN_192bitValue* source
)
{
    uint32_t ctr;

    for (ctr = 0; ctr < 6; ctr++)
    {
        dest->as_uint32_t[ctr] = source->as_uint32_t[ctr];
    }
}

/// Gets an uint8_t as third parameter that shall be zero or one.
void
conditionalMove_192bitValue(
    UN_192bitValue*       r,
    const UN_192bitValue* x,
    uint8_t                 b
)
{
    int32_t mask = b;
    uint32_t ctr;

    mask = -mask;

    for (ctr = 0; ctr < 6; ctr++)
    {
        r->as_uint32_t[ctr] ^= mask & (x->as_uint32_t[ctr] ^ r->as_uint32_t[ctr]);
    }
}

/// Gets an uint8_t as third parameter that shall be zero or one.
void
conditionalMove_256bitValue(
    UN_256bitValue*       r,
    const UN_256bitValue* x,
    uint8_t                 b
)
{
    int32_t mask = b;
    uint32_t ctr;

    mask = -mask;

    for (ctr = 0; ctr < 8; ctr++)
    {
        r->as_uint32_t[ctr] ^= mask & (x->as_uint32_t[ctr] ^ r->as_uint32_t[ctr]);
    }
}

// Multiplies val by 2 by shifting all bits to the left by 1 position.
void shiftLeftOne(UN_256bitValue* val) {
    uint32_t overflow;

    val->as_uint32_t[7] <<= 1;
    int i;
    for(i=7;i>=1;i--) {
        overflow = ((val->as_uint32_t[i-1] & (1 << 31)) >> 31);
        val->as_uint32_t[i] += overflow;
        val->as_uint64_t[i-1] <<= 1;
    }
}

// Divides val by 2 by shifting to the right, value is assumed to be < 2^255-19
// in case of negative value, sign is kept
 void shiftRightOne(UN_256bitValue* val) {
    uint32_t underflow;

    val->as_uint32_t[0] >>= 1;
    int i;
    uint32_t sign = val->as_uint32_t[7] & 0x80000000;
    for(i=0;i<7;i++) {
        underflow = val->as_uint32_t[i+1] & 1;
        val->as_uint32_t[i] += (underflow << 31);
        val->as_uint32_t[i+1] >>= 1;
    }
    val->as_uint32_t[7] |= sign;
 }

// Returns 1 if values are not equal, returns 1 otherwise
uint32_t isEqual_256bitvalue(const UN_256bitValue* x, const UN_256bitValue* y) {
    uint32_t result = 0;
    int i;
    for(i=0;i<8;i++) {
        result |= x->as_uint32_t[i] ^ y->as_uint32_t[i];
    }
    return result;
 }
