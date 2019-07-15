/*                          =======================
  ============================ C/C++ HEADER FILE =============================
                            =======================                      

    \file crypto_target_config.h

    Target specific adaptions. Defines inttypes and

    The target config header is required to provide definitions for the types

    uint8_t ... uint64
    int8_t  ... int64

    and the macros FORCE_INLINE and NO_INLINE

    In the target specific target config header, it is possible to define symbols activating
    specific optimized assembly functions.
 
    \Author: B. Haase, Endress + Hauser Conducta GmbH & Co. KG

    License: CC0 1.0 (http://creativecommons.org/publicdomain/zero/1.0/legalcode)
  ============================================================================*/

#ifndef CRYPTO_TARGET_CONFIG_HEADER_
#define CRYPTO_TARGET_CONFIG_HEADER_

#include "crypto_target_config_cortexM4.h"

#ifndef FORCE_INLINE
#define FORCE_INLINE
#endif

#ifndef NO_INLINE
#define NO_INLINE
#endif

#endif // #ifdef TARGET_CONFIG_HEADER_
