///////////////////////////////////////////////////////////////////////////////
// IronBridge RNG Provider Service
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _INCLUDE_IBRAND_SERVICE_KEM_H_
#define _INCLUDE_IBRAND_SERVICE_KEM_H_

#include "../ibrand_common/my_utilslib.h"
#include "ibrand_service_utils.h"

#define PQCRYPTO_LWEKE 1
#define PQCRYPTO_OQS   2
//#define WHICH_PQCRYPTO PQCRYPTO_LWEKE
#define WHICH_PQCRYPTO PQCRYPTO_OQS

#if (WHICH_PQCRYPTO == PQCRYPTO_LWEKE)
#include "../PQCrypto-LWEKE/src/api_frodo640.h"
#endif
#if (WHICH_PQCRYPTO == PQCRYPTO_OQS)
#include "oqs/kem.h"
#endif


#if (WHICH_PQCRYPTO == PQCRYPTO_LWEKE)
#define SYSTEM_NAME    "FrodoKEM-640"
#define crypto_kem_keypair            crypto_kem_keypair_Frodo640
#define crypto_kem_enc                crypto_kem_enc_Frodo640
#define crypto_kem_dec                crypto_kem_dec_Frodo640

// int crypto_kem_keypair_Frodo640 (unsigned char *pk, unsigned char *sk);
// int crypto_kem_enc_Frodo640     (unsigned char *ct, unsigned char *ss, const unsigned char *pk);
// int crypto_kem_dec_Frodo640     (unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
#endif

extern int KemDecapsulateSharedSecret(char *kemAlgorithm,
                                      tLSTRING *pSharedSecret,
                                      const tLSTRING *pEncapsulatedSharedSecret,
                                      const tLSTRING *pKemSecretKey);

#endif // _INCLUDE_IBRAND_SERVICE_KEM_H_
