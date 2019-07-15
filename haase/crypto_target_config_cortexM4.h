/*                          =======================
  ============================ C/C++ HEADER FILE =============================
                            =======================                      

    \file crypto_target_config_cortexM4.h

    Target specific adaptions for Cortex M4
 
    \Author: B. Haase, Endress + Hauser Conducta GmbH & Co. KG

    License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)
  ============================================================================*/
#ifndef TARGET_CONFIG_HEADER_CORTEX_M4_
#define TARGET_CONFIG_HEADER_CORTEX_M4_

// We assume, that we are compiling with GCC or with CLANG

#include <stdint.h>

#ifndef NACL_NO_ASM_OPTIMIZATION

#define CRYPTO_HAS_ASM_HSALSA20_BLOCK
#define CRYPTO_HAS_ASM_POLY1305_UPDATE_STATE

#define CRYPTO_TARGET_HAS_ASM_SHA512_CORE
#define CRYPTO_TARGET_HAS_ASM_ENDIAN_SWAP

// Assembly mpy 256x256 is significantly faster than the C version.
//#define CRYPTO_HAS_ASM_MPY_256
//#define CRYPTO_HAS_ASM_REDUCE_25519
//#define CRYPTO_HAS_ASM_FE25519_MPY121666
#define CRYPTO_HAS_ASM_FE25519_MUL
#define CRYPTO_HAS_ASM_FE25519_SQUARE
//#define CRYPTO_HAS_ASM_FE25519_ADD

// Assembly squaring for 256x256 => 512 is considerably faster than the C version
//#define CRYPTO_HAS_ASM_SQR_256
//#define CRYPTO_HAS_ASM_MPY_128
//#define CRYPTO_HAS_ASM_SQR_128
//#define CRYPTO_HAS_ASM_MPY_192
//#define CRYPTO_HAS_ASM_SQR_192
//#define CRYPTO_HAS_ASM_REDUCE_19119
//#define CRYPTO_HAS_ASM_FE19119_MPY132355

#define CRYPTO_HAS_ASM_SIPHASH_2xITERATE_STATE
#define CRYPTO_HAS_ASM_SIPHASH_24_ALIGNED
#define CRYPTO_HAS_ASM_CHASKEY_ALIGNED
#define CRYPTO_HAS_ASM_CHASKEY_LTS_ALIGNED

#endif

#if defined(__clang__) || defined(__GNUC__)

#define FORCE_INLINE inline __attribute__ ((__always_inline__))
#define NO_INLINE __attribute__ ((noinline))

#else

#define FORCE_INLINE
#define NO_INLINE

#endif



#endif // #ifdef TARGET_CONFIG_HEADER_
