// Authors: Bjoern Haase, Niels Samwel 
//
// License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)

#include "../include/sc25519.h"
#include "../include/montgomery_reduction.h"

#define BARRET_REDUCTION 1
#define MONTGOMERY_REDUCTION 2
#define REDUCTION_TYPE BARRET_REDUCTION

#if (REDUCTION_TYPE == BARRET_REDUCTION)

// Fixme: This code won't work on big endian targets.
static const UN_288bitValue sc25519_scalar =
{{
 0xed,  0xd3,  0xf5,  0x5c,  0x1a,  0x63,  0x12,  0x58,
 0xd6,  0x9c,  0xf7,  0xa2,  0xde,  0xf9,  0xde,  0x14,
 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
 0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x10
}};

#define uint32_scalar sc25519_scalar.as_uint32_t

#else

static const UNMontgomeryConstants256 sc25519_scalarMontgomeryPrecalc = {{
 0x01,  0x0f,  0x9c,  0x44,  0xe3,  0x11,  0x06,  0xa4, 
 0x47,  0x93,  0x85,  0x68,  0xa7,  0x1b,  0x0e,  0xd0, 
 0x65,  0xbe,  0xf5,  0x17,  0xd2,  0x73,  0xec,  0xce, 
 0x3d,  0x9a,  0x30,  0x7c,  0x1b,  0x41,  0x99,  0x03, 
 0xed,  0xd3,  0xf5,  0x5c,  0x1a,  0x63,  0x12,  0x58, 
 0xd6,  0x9c,  0xf7,  0xa2,  0xde,  0xf9,  0xde,  0x14, 
 0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 
 0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x10, 
 0x1b,  0x7e,  0x54,  0x12
}};

#define uint32_scalar sc25519_scalarMontgomeryPrecalc.constants.prime.as_uint32_t

#endif

static int32_t
bigint_sub(
    uint32_t*       dest,
    const uint32_t* sub,
    uint32_t        numberOfWords
)
{
    unsigned ctr;
    int64_t    accu = 0;

    for (ctr = 0; ctr < numberOfWords; ctr ++)
    {
        accu += dest[ctr];
        accu -= sub[ctr];
        dest[ctr] = (uint32_t)accu;
        accu >>= 32;
    }
    return (int32_t)accu;
}

static int32_t
bigint_add(
    uint32_t*       dest,
    const uint32_t* addend,
    uint32_t        numberOfWords
)
{
    unsigned ctr;
    int64_t    accu = 0;

    for (ctr = 0; ctr < numberOfWords; ctr ++)
    {
        accu += dest[ctr];
        accu += addend[ctr];
        dest[ctr] = (uint32_t)accu;
        accu >>= 32;
    }
    return (int32_t)accu;
}

#if 1

/* substracts the prime in case that the result is non-negative.
   gets a pointer to a temp buffer in order to reduce stack consumption */
static void
sc25519_reduceAddSub(
    sc25519* valueToReduce,
    sc25519* tempBufferSuppliedByCaller
)
{
    int32_t didUnderflowHappen;

    cpy_256bitvalue(tempBufferSuppliedByCaller, valueToReduce);
    didUnderflowHappen = bigint_sub(tempBufferSuppliedByCaller->as_uint32_t,
                                    uint32_scalar,
                                    8);
    conditionalMove_256bitValue(valueToReduce, tempBufferSuppliedByCaller,
                                (uint8_t) (~didUnderflowHappen) & 1);
}

#else

/* substracts the prime in case that the result is non-negative.
   gets a pointer to a temp buffer in order to reduce stack consumption */
static void
sc25519_reduceAddSub(
    sc25519* valueToReduce,
    sc25519* tempBufferSuppliedByCaller
)
{
    int32_t didUnderflowHappen;

    didUnderflowHappen = montgomery_mnac_U16 (valueToReduce->as_uint32_t, 1, uint32_scalar);
    montgomery_mac_lowU16 (valueToReduce->as_uint32_t, 
                           didUnderflowHappen * didUnderflowHappen, 
                           uint32_scalar);
}

#endif

void
sc25519_from32bytes(
    sc25519*            r,
    const uint8_t x[32]
)
{
    UN_512bitValue temp;
    uint8_t          ctr;

    for (ctr = 0; ctr < 32; ctr++)
    {
        // Fixme: This code won't work on big endian targets.
        temp.as_uint8_t[ctr] = x[ctr];
    }

    for (ctr = 8; ctr < 16; ctr++)
    {
        temp.as_uint32_t[ctr] = 0;
    }
    sc25519_reduce(&temp);

    for (ctr = 0; ctr < 8; ctr++)
    {
        r->as_uint32_t[ctr] = temp.as_uint32_t[ctr];
    }
}

void
sc25519_from64bytes(
    sc25519*            r,
    const uint8_t x[64]
)
{
    UN_512bitValue temp;
    uint8_t          ctr;

    for (ctr = 0; ctr < 64; ctr++)
    {
        // Fixme: This code won't work on big endian targets.
        temp.as_uint8_t[ctr] = x[ctr];
    }
    sc25519_reduce(&temp);

    for (ctr = 0; ctr < 8; ctr++)
    {
        r->as_uint32_t[ctr] = temp.as_uint32_t[ctr];
    }
}

void
sc25519_to32bytes(
    uint8_t  r[32],
    const sc25519* x
)
{
    uint8_t ctr;

    for (ctr = 0; ctr < 32; ctr++)
    {
        // Fixme: This code won't work on big endian targets.
        r[ctr] = x->as_uint8_t[ctr];
    }
}

void
sc25519_add(
    sc25519*       result,
    const sc25519* addend1,
    const sc25519* addend2
)
{
    UN_256bitValue tmp;

    cpy_256bitvalue(result, addend1);
    bigint_add(result->as_uint32_t, addend2->as_uint32_t, 8);
    sc25519_reduceAddSub(result, &tmp);

}

void
sc25519_sub(
    sc25519*       result,
    const sc25519* addend,
    const sc25519* valueToSubstract
)
{
    UN_256bitValue tmp;
    int didUnderflowHappen;

    cpy_256bitvalue(result, addend);
    didUnderflowHappen = bigint_sub( result->as_uint32_t,
                                     valueToSubstract->as_uint32_t,
                                     8);
    {
        int i;
        for (i = 0; i < 8; i ++)
        {
            tmp.as_uint32_t[i] = uint32_scalar[i];
        }
    }
    bigint_add (tmp.as_uint32_t, result->as_uint32_t,8);

    conditionalMove_256bitValue((UN_256bitValue *) result, &tmp,
                                (uint8_t) (didUnderflowHappen & 1));

}

#if (REDUCTION_TYPE == BARRET_REDUCTION)

/* Calculates the barret reduction modulo the scalar prime.
   returns the reduced result in the lower 256 bits. */
void
sc25519_reduce(
    UN_512bitValue* valueToReduce
)
{
    /* use Barret reduction. Multiply with 288 bits so that all intermediate
       results are also aligned to four-byte boundaries. */
    static const uint32_t u32_mu[9] =
    {
        0x0a2c131bUL, 0xed9ce5a3UL, 0x086329a7UL, 0x2106215dUL,
        0xffffffebUL, 0xffffffffUL, 0xffffffffUL, 0xffffffffUL,
        0xfUL
    };

    UN_288bitValue* valueForBarretMpy =
        (UN_288bitValue*)&valueToReduce->as_uint32_t[7];
    UN_288bitValue* u288_mu = (UN_288bitValue*)u32_mu;
    const UN_288bitValue* u288_pr252 = &sc25519_scalar;
    UN_576bitValue  intermResultBarret;

    multiply288x288(&intermResultBarret, u288_mu, valueForBarretMpy);
    {
        UN_288bitValue* approximateResultOfDivision =
            (UN_288bitValue*)&intermResultBarret.as_uint32_t[9];
        UN_576bitValue valueToSubstract;
        multiply288x288(&valueToSubstract,
                        approximateResultOfDivision,
                        u288_pr252);


        bigint_sub(valueToReduce->as_uint32_t, valueToSubstract.as_uint32_t,
                   16);
            /* due to rounding the true result of the division may be wrong by one (or two?).
               we need to conditionally substract the prime if the result of the substraction
               is nonnegative. */
    }

    sc25519_reduceAddSub(&valueToReduce->as_256_bitValue[0],
                         &valueToReduce->as_256_bitValue[1]);
    sc25519_reduceAddSub(&valueToReduce->as_256_bitValue[0],
                         &valueToReduce->as_256_bitValue[1]);
}
#else

void
sc25519_reduce(
    UN_512bitValue* valueToReduce
)
{
   UN_256bitValue tmp;

   montgomery_reduce (&tmp,
                      valueToReduce, &sc25519_scalarMontgomeryPrecalc.constants);
   multiply256x256 (valueToReduce, &tmp, 
                    &sc25519_scalarMontgomeryPrecalc.constants.kSquare); 
   montgomery_reduce (&valueToReduce->as_256_bitValue [0],
                      valueToReduce, &sc25519_scalarMontgomeryPrecalc.constants);
}

#endif


#if (REDUCTION_TYPE == BARRET_REDUCTION)

/* Multiplies and calculates the barret reduction modulo the scalar prime.  */
void
sc25519_mul(
    sc25519*       r,
    const sc25519* x,
    const sc25519* y
)
{
    UN_512bitValue temp;

    multiply256x256(&temp, x, y);

    sc25519_reduce(&temp);
    cpy_256bitvalue(r, &temp.as_256_bitValue[0]);
}

void
sc25519_sqr(
	sc25519*       r,
	const sc25519* x
	)
{
	UN_512bitValue temp;

	square256(&temp, x);

	sc25519_reduce(&temp);
	cpy_256bitvalue(r, &temp.as_256_bitValue[0]);
}

#else

void
sc25519_mul(
    sc25519*       r,
    const sc25519* x,
    const sc25519* y
)
{
   UN_512bitValue tmp;
   multiply256x256 (&tmp, x,y);
   montgomery_reduce (r,&tmp, &sc25519_scalarMontgomeryPrecalc.constants);
   multiply256x256 (&tmp, r, &sc25519_scalarMontgomeryPrecalc.constants.kSquare); 
   montgomery_reduce (r,&tmp, &sc25519_scalarMontgomeryPrecalc.constants);
}

void
sc25519_sqr(
	sc25519*       r,
	const sc25519* x
	)
{
	UN_512bitValue tmp;
	square256(&tmp, x);
	montgomery_reduce(r, &tmp, &sc25519_scalarMontgomeryPrecalc.constants);
	multiply256x256(&tmp, r, &sc25519_scalarMontgomeryPrecalc.constants.kSquare);
	montgomery_reduce(r, &tmp, &sc25519_scalarMontgomeryPrecalc.constants);
}

#endif

/// convert the scalar s to a representation of 64 or 72 signed chars containing
/// 4 bits each. (NAF-Form with values -8 .. + 8).
/// This is done for speedup of the fixed-window scalar multiplication
/// later on, that processes 4 bits in each step.
void
sc25519_window4(
    signed char    r[SC25519_WINDOW4_SIZE],
    const sc25519* s
)
{
    char          carry;
    uint8_t i;

    for (i = 0; i < 32; i++)
    {
        r[2 * i] = s->as_uint8_t[i] & 15;
        r[2 * i + 1] = s->as_uint8_t[i] >> 4;
    }

    /* Making the result signed and limited to the range -8 ... +8 for the signed NAF form. */
    carry = 0;

    for (i = 0; i < (SC25519_WINDOW4_SIZE - 1); i++)
    {
        r[i] += carry;
        r[i + 1] += r[i] >> 4;
        r[i] &= 15;
        carry = r[i] >> 3;
        r[i] -= carry << 4;
    }
    r[SC25519_WINDOW4_SIZE - 1] += carry;
}

// Returns 0 if x>y, returns 1 otherwise
 int greaterThan(const UN_256bitValue* x, const UN_256bitValue* y) {
    // int i;
    // for(i=7;i>=0;i--) {
    //     if(x->as_uint32_t[i] > y->as_uint32_t[i])
    //         return 1;
    //     else if(x->as_uint32_t[i] < y->as_uint32_t[i])
    //         return 0;
    // }
    // return 0;
    UN_256bitValue tmp;
    cpy_256bitvalue(&tmp, x);
    bigint_sub(tmp.as_uint32_t, y->as_uint32_t, 8);
    return tmp.as_uint32_t[7] >> 31;
 }

// binary extended gcd algorithm based on Alg. 14.61 in the Handbook of Applied Cryptography
//
void sc25519_binary_extended_gcd(UN_256bitValue *R, const UN_256bitValue *X, const UN_256bitValue *Y) {
    UN_256bitValue B, D, v, u, g, x, y, zero;
    cpy_256bitvalue(&x, X);
    cpy_256bitvalue(&y, Y);
    setone_256bitvalue(&g);
    while(((x.as_uint8_t[0] & 1) == 0)  && ((y.as_uint8_t[0] & 1) == 0)) {
        shiftRightOne(&x);
        shiftRightOne(&y);
        shiftLeftOne(&g);
    }
    cpy_256bitvalue(&u, &x);
    cpy_256bitvalue(&v, &y);
    setzero_256bitvalue(&B);
    setone_256bitvalue(&D);

    setzero_256bitvalue(&zero);
    while(isEqual_256bitvalue(&u, &zero) > 0) {
        while((u.as_uint8_t[0] & 1) == 0) {
            shiftRightOne(&u);
            if((B.as_uint8_t[0] & 1) == 0) {
                shiftRightOne(&B);
            } else {
                bigint_sub(B.as_uint32_t, x.as_uint32_t, 8);
                shiftRightOne(&B);
            }
        }

        while((v.as_uint8_t[0] & 1) == 0) {
            shiftRightOne(&v);
            if((D.as_uint8_t[0] & 1) == 0) {
                shiftRightOne(&D);
            } else {
                bigint_sub(D.as_uint32_t, x.as_uint32_t, 8);
                shiftRightOne(&D);
            }
        }
        if(!greaterThan(&u, &v) || (isEqual_256bitvalue(&u, &v) == 0)) {
            bigint_sub(u.as_uint32_t, v.as_uint32_t, 8);
            bigint_sub(B.as_uint32_t, D.as_uint32_t, 8);
        } else {
            bigint_sub(v.as_uint32_t, u.as_uint32_t, 8);
            bigint_sub(D.as_uint32_t, B.as_uint32_t, 8);   
        }
    }
    cpy_256bitvalue(R, &D);
}

// Attention: Variable time execution due to the extended GCD algorithm!
void sc25519_inverse(UN_256bitValue *R, const UN_256bitValue *X) {
    UN_256bitValue order = {{
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 
    }};
    sc25519_binary_extended_gcd(R, &order, X);
    // In case R < 0, add order until positive
    while((R->as_uint32_t[7] & 0x80000000) != 0)
        bigint_add(R->as_uint32_t, order.as_uint32_t, 8);
}
