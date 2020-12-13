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

#ifndef tERRORCODE
#define tERRORCODE int
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_IBKEM_FLOOR 19200
#define ERC_IBKEM_NOMEM_FOR_URL                              19210
#define ERC_IBKEM_PARAMERR_UNKNOWN_ALGO_ID                   19220
#define ERC_IBKEM_PARAMERR_ALGO_NOT_SUPPORTED                19230
#define ERC_IBKEM_PARAMERR_ALGO_NOT_SUPPORTED_OR_NOT_ENABLED 19240
#define ERC_IBKEM_ALGO_INSTANTIATE_FAILED                    19250
#define ERC_IBKEM_SHSEC_BUFFER_TOO_SMALL                     19260
#define ERC_IBKEM_SHSEC_SIZE_ERROR                           19270
#define ERC_IBKEM_KEMKEY_SIZE_ERROR                          19280
#define ERC_IBKEM_KEM_DECAP_FAILED                           19290

#include "oqs/kem.h"

extern const char *KemLookupOqsAlgorithmName(int CqcAlgorithmId);
extern bool KemAlgorithmIsValid(const char *algorithmName, bool *pIsSupported, bool *pIsEnabled);
extern tERRORCODE KemDecapsulateSharedSecret(int cqcKemAlgorithmId,
                                             tLSTRING *pSharedSecret,
                                             const tLSTRING *pEncapsulatedSharedSecret,
                                             const tLSTRING *pKemSecretKey);

#endif // _INCLUDE_IBRAND_SERVICE_KEM_H_
