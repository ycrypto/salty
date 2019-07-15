/*                          =======================
  ============================ C/C++ HEADER FILE =============================
                            =======================                      

    \file sc25519.h

    Defines the sc25519 type used for the ed25519 signature algorithm.

    Provides the same interface as the corresponding header in avrnacl of
    Michael Hutter and Peter Schwabe.
 
    \Author: B. Haase, Endress + Hauser Conducta GmbH & Co. KG

    License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)
  ============================================================================*/

#ifndef SC25519_HEADER_
#define SC25519_HEADER_

#include "../include/bigint.h"


typedef UN_256bitValue sc25519;

void
sc25519_to32bytes(
    uint8_t  r[32],
    const sc25519* x
);

void
sc25519_from64bytes(
    sc25519*            r,
    const uint8_t x[64]
);

void
sc25519_from32bytes(
    sc25519*            r,
    const uint8_t x[32]
);

#define SC25519_WINDOW4_SIZE (64)

#define SC25519_INITIALIZER_FOR_ONE_HALF { \
      0xf7,  0xe9,  0x7a,  0x2e,  0x8d,  0x31,  0x09,  0x2c,\
      0x6b,  0xce,  0x7b,  0x51,  0xef,  0x7c,  0x6f,  0x0a,\
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,\
      0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x08 }

/// convert s to a representation of 64 signed chars containing
/// 4 bits each. This is done for speedup of the scalar multiplication
/// later on, that processes 4 bits in each step.
void
sc25519_window4(
    signed char    r[SC25519_WINDOW4_SIZE],
    const sc25519* s
);

/// Generate an interleave table for the algorithm, that simultaneously computes
/// the sum of two scalar products.
void
sc25519_2interleave1(
    uint8_t  r[255],
    const sc25519* s1,
    const sc25519* s2
);

void
sc25519_add(
    sc25519*       result,
    const sc25519* addend1,
    const sc25519* addend2
);

void
sc25519_sub(
    sc25519*       result,
    const sc25519* addend,
    const sc25519* valueToSubstract
);

void
sc25519_mul(
    sc25519*       r,
    const sc25519* x,
    const sc25519* y
);

void
sc25519_sqr(
	sc25519*       r,
	const sc25519* x
	);

/* Calculates the result modulo the scalar prime.
returns the result in the lower 256 bits of the input operand. */
void
sc25519_reduce(UN_512bitValue* valueToReduce);


/// inversion modulo point group order.
void sc25519_invert(sc25519 *result, const sc25519* in);

void sc25519_inverse(UN_256bitValue *R, const UN_256bitValue *X);

void sc25519_binary_extended_gcd(UN_256bitValue *R, const UN_256bitValue *X, const UN_256bitValue *Y);

#endif // #ifndef SC25519_HEADER_
